"""
Расширенные настройки для GUI
Все параметры из cli.py --help
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QCheckBox,
    QPushButton, QFileDialog, QTabWidget
)
from typing import Dict, Any


class AdvancedSettingsWidget(QWidget):
    """Виджет расширенных настроек"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Настройка интерфейса"""
        layout = QVBoxLayout(self)
        
        # Создаем вкладки для разных категорий
        tabs = QTabWidget()
        tabs.addTab(self.create_mode_settings(), "Режим")
        tabs.addTab(self.create_timeout_settings(), "Таймауты")
        tabs.addTab(self.create_dpi_settings(), "DPI")
        tabs.addTab(self.create_performance_settings(), "Производительность")
        tabs.addTab(self.create_payload_settings(), "Payload")
        
        layout.addWidget(tabs)
    
    def create_mode_settings(self) -> QWidget:
        """Настройки режима анализа"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Режим
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Режим анализа:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["quick", "balanced", "comprehensive", "deep"])
        self.mode_combo.setCurrentText("balanced")
        mode_layout.addWidget(self.mode_combo)
        layout.addLayout(mode_layout)
        
        # Макс попыток
        trials_layout = QHBoxLayout()
        trials_layout.addWidget(QLabel("Макс. попыток:"))
        self.max_trials_spin = QSpinBox()
        self.max_trials_spin.setRange(1, 100)
        self.max_trials_spin.setValue(10)
        trials_layout.addWidget(self.max_trials_spin)
        layout.addLayout(trials_layout)
        
        # Опции
        self.fingerprint_check = QCheckBox("DPI fingerprinting")
        self.fingerprint_check.setChecked(True)
        layout.addWidget(self.fingerprint_check)
        
        self.failure_analysis_check = QCheckBox("Анализ ошибок")
        self.failure_analysis_check.setChecked(True)
        layout.addWidget(self.failure_analysis_check)
        
        self.advanced_dns_check = QCheckBox("Расширенное DNS")
        layout.addWidget(self.advanced_dns_check)
        
        self.enable_scapy_check = QCheckBox("Включить Scapy")
        layout.addWidget(self.enable_scapy_check)
        
        layout.addStretch()
        return widget
    
    def create_timeout_settings(self) -> QWidget:
        """Настройки таймаутов"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # TCP timeout
        tcp_layout = QHBoxLayout()
        tcp_layout.addWidget(QLabel("TCP подключение (сек):"))
        self.connect_timeout_spin = QDoubleSpinBox()
        self.connect_timeout_spin.setRange(0.1, 30.0)
        self.connect_timeout_spin.setValue(1.5)
        self.connect_timeout_spin.setSingleStep(0.1)
        tcp_layout.addWidget(self.connect_timeout_spin)
        layout.addLayout(tcp_layout)
        
        # TLS timeout
        tls_layout = QHBoxLayout()
        tls_layout.addWidget(QLabel("TLS handshake (сек):"))
        self.tls_timeout_spin = QDoubleSpinBox()
        self.tls_timeout_spin.setRange(0.1, 30.0)
        self.tls_timeout_spin.setValue(2.0)
        self.tls_timeout_spin.setSingleStep(0.1)
        tls_layout.addWidget(self.tls_timeout_spin)
        layout.addLayout(tls_layout)
        
        layout.addStretch()
        return widget
    
    def create_dpi_settings(self) -> QWidget:
        """Настройки DPI стратегий"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Desync mode
        desync_layout = QHBoxLayout()
        desync_layout.addWidget(QLabel("DPI Desync:"))
        self.dpi_desync_combo = QComboBox()
        self.dpi_desync_combo.addItems(["split", "fake", "disorder", "multisplit"])
        desync_layout.addWidget(self.dpi_desync_combo)
        layout.addLayout(desync_layout)
        
        # Split positions
        split_pos_layout = QHBoxLayout()
        split_pos_layout.addWidget(QLabel("Split позиции:"))
        self.dpi_split_pos_input = QLineEdit()
        self.dpi_split_pos_input.setPlaceholderText("3,10,sni")
        split_pos_layout.addWidget(self.dpi_split_pos_input)
        layout.addLayout(split_pos_layout)
        
        # Fooling
        fooling_layout = QHBoxLayout()
        fooling_layout.addWidget(QLabel("Fooling:"))
        self.dpi_fooling_input = QLineEdit()
        self.dpi_fooling_input.setPlaceholderText("badsum,badseq,md5sig")
        fooling_layout.addWidget(self.dpi_fooling_input)
        layout.addLayout(fooling_layout)
        
        # TTL
        ttl_layout = QHBoxLayout()
        ttl_layout.addWidget(QLabel("TTL:"))
        self.dpi_ttl_spin = QSpinBox()
        self.dpi_ttl_spin.setRange(1, 255)
        self.dpi_ttl_spin.setValue(1)
        ttl_layout.addWidget(self.dpi_ttl_spin)
        layout.addLayout(ttl_layout)
        
        # Repeats
        repeats_layout = QHBoxLayout()
        repeats_layout.addWidget(QLabel("Повторы:"))
        self.dpi_repeats_spin = QSpinBox()
        self.dpi_repeats_spin.setRange(1, 10)
        self.dpi_repeats_spin.setValue(1)
        repeats_layout.addWidget(self.dpi_repeats_spin)
        layout.addLayout(repeats_layout)
        
        # Split count
        count_layout = QHBoxLayout()
        count_layout.addWidget(QLabel("Split count:"))
        self.dpi_split_count_spin = QSpinBox()
        self.dpi_split_count_spin.setRange(2, 20)
        self.dpi_split_count_spin.setValue(6)
        count_layout.addWidget(self.dpi_split_count_spin)
        layout.addLayout(count_layout)
        
        # Seqovl
        seqovl_layout = QHBoxLayout()
        seqovl_layout.addWidget(QLabel("Split seqovl:"))
        self.dpi_seqovl_spin = QSpinBox()
        self.dpi_seqovl_spin.setRange(0, 100)
        self.dpi_seqovl_spin.setValue(0)
        seqovl_layout.addWidget(self.dpi_seqovl_spin)
        layout.addLayout(seqovl_layout)
        
        layout.addStretch()
        return widget
    
    def create_performance_settings(self) -> QWidget:
        """Настройки производительности"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Параллелизм
        parallel_layout = QHBoxLayout()
        parallel_layout.addWidget(QLabel("Параллельных доменов:"))
        self.parallel_spin = QSpinBox()
        self.parallel_spin.setRange(1, 50)
        self.parallel_spin.setValue(15)
        parallel_layout.addWidget(self.parallel_spin)
        layout.addLayout(parallel_layout)
        
        self.sequential_check = QCheckBox("Последовательная обработка")
        layout.addWidget(self.sequential_check)
        
        self.no_fail_fast_check = QCheckBox("Отключить fail-fast")
        layout.addWidget(self.no_fail_fast_check)
        
        # Оптимизация
        self.optimize_params_check = QCheckBox("Оптимизация параметров")
        layout.addWidget(self.optimize_params_check)
        
        opt_strategy_layout = QHBoxLayout()
        opt_strategy_layout.addWidget(QLabel("Стратегия:"))
        self.opt_strategy_combo = QComboBox()
        self.opt_strategy_combo.addItems(["grid_search", "random_search", "bayesian", "evolutionary"])
        opt_strategy_layout.addWidget(self.opt_strategy_combo)
        layout.addLayout(opt_strategy_layout)
        
        # Эволюция
        population_layout = QHBoxLayout()
        population_layout.addWidget(QLabel("Популяция:"))
        self.population_spin = QSpinBox()
        self.population_spin.setRange(5, 100)
        self.population_spin.setValue(10)
        population_layout.addWidget(self.population_spin)
        layout.addLayout(population_layout)
        
        generations_layout = QHBoxLayout()
        generations_layout.addWidget(QLabel("Поколений:"))
        self.generations_spin = QSpinBox()
        self.generations_spin.setRange(1, 50)
        self.generations_spin.setValue(3)
        generations_layout.addWidget(self.generations_spin)
        layout.addLayout(generations_layout)
        
        mutation_layout = QHBoxLayout()
        mutation_layout.addWidget(QLabel("Мутация:"))
        self.mutation_spin = QDoubleSpinBox()
        self.mutation_spin.setRange(0.0, 1.0)
        self.mutation_spin.setValue(0.2)
        self.mutation_spin.setSingleStep(0.05)
        mutation_layout.addWidget(self.mutation_spin)
        layout.addLayout(mutation_layout)
        
        layout.addStretch()
        return widget
    
    def create_payload_settings(self) -> QWidget:
        """Настройки payload"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Custom payload
        custom_layout = QHBoxLayout()
        custom_layout.addWidget(QLabel("Custom payload:"))
        self.custom_payload_input = QLineEdit()
        self.custom_payload_input.setPlaceholderText("Путь к .bin файлу")
        custom_layout.addWidget(self.custom_payload_input)
        
        browse_btn = QPushButton("📁")
        browse_btn.clicked.connect(self.browse_custom_payload)
        custom_layout.addWidget(browse_btn)
        layout.addLayout(custom_layout)
        
        # Fake payload
        fake_layout = QHBoxLayout()
        fake_layout.addWidget(QLabel("Fake payload:"))
        self.fake_payload_input = QLineEdit()
        self.fake_payload_input.setPlaceholderText("PAYLOADTLS, PAYLOADHTTP, или путь")
        fake_layout.addWidget(self.fake_payload_input)
        layout.addLayout(fake_layout)
        
        layout.addStretch()
        return widget
    
    def browse_custom_payload(self):
        """Выбор custom payload файла"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выберите payload файл", "", "Binary Files (*.bin);;All Files (*)"
        )
        if file_path:
            self.custom_payload_input.setText(file_path)
    
    def get_cli_args(self) -> list:
        """Получить аргументы командной строки из настроек"""
        args = []
        
        # Режим
        args.extend(['--mode', self.mode_combo.currentText()])
        args.extend(['--max-trials', str(self.max_trials_spin.value())])
        
        # Таймауты
        args.extend(['--connect-timeout', str(self.connect_timeout_spin.value())])
        args.extend(['--tls-timeout', str(self.tls_timeout_spin.value())])
        
        # Опции
        if not self.fingerprint_check.isChecked():
            args.append('--no-fingerprinting')
        if not self.failure_analysis_check.isChecked():
            args.append('--no-failure-analysis')
        if self.advanced_dns_check.isChecked():
            args.append('--advanced-dns')
        if self.enable_scapy_check.isChecked():
            args.append('--enable-scapy')
        
        # DPI
        args.extend(['--dpi-desync', self.dpi_desync_combo.currentText()])
        if self.dpi_split_pos_input.text():
            args.extend(['--dpi-desync-split-pos', self.dpi_split_pos_input.text()])
        if self.dpi_fooling_input.text():
            args.extend(['--dpi-desync-fooling', self.dpi_fooling_input.text()])
        args.extend(['--dpi-desync-ttl', str(self.dpi_ttl_spin.value())])
        args.extend(['--dpi-desync-repeats', str(self.dpi_repeats_spin.value())])
        args.extend(['--dpi-desync-split-count', str(self.dpi_split_count_spin.value())])
        args.extend(['--dpi-desync-split-seqovl', str(self.dpi_seqovl_spin.value())])
        
        # Производительность
        args.extend(['--parallel', str(self.parallel_spin.value())])
        if self.sequential_check.isChecked():
            args.append('--sequential')
        if self.no_fail_fast_check.isChecked():
            args.append('--no-fail-fast')
        
        # Оптимизация
        if self.optimize_params_check.isChecked():
            args.append('--optimize-parameters')
            args.extend(['--optimization-strategy', self.opt_strategy_combo.currentText()])
        
        # Эволюция
        args.extend(['--population', str(self.population_spin.value())])
        args.extend(['--generations', str(self.generations_spin.value())])
        args.extend(['--mutation-rate', str(self.mutation_spin.value())])
        
        # Payload
        if self.custom_payload_input.text():
            args.extend(['--custom-payload', self.custom_payload_input.text()])
        if self.fake_payload_input.text():
            args.extend(['--fake-payload-file', self.fake_payload_input.text()])
        
        return args
