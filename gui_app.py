#!/usr/bin/env python3
"""
Flet GUI для Recon DPI Bypass System
Кроссплатформенное приложение для Windows и Android
"""

import flet as ft
import asyncio
import platform
from typing import Optional
from pathlib import Path

# Импорты из вашего проекта
try:
    from core.adaptive_engine import AdaptiveEngine
    from core.strategy_evaluator import StrategyEvaluator
    from core.domain_manager import DomainManager
    CORE_AVAILABLE = True
except ImportError:
    CORE_AVAILABLE = False


class ReconDPIApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Recon DPI Bypass"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.padding = 20
        
        # Определяем платформу
        self.is_mobile = page.platform in [ft.PagePlatform.ANDROID, ft.PagePlatform.IOS]
        self.is_windows = platform.system() == "Windows"
        
        # Инициализация компонентов
        self.domain_manager = DomainManager() if CORE_AVAILABLE else None
        self.adaptive_engine = None
        
        # UI компоненты
        self.domain_input = ft.TextField(
            label="Домен для тестирования",
            hint_text="example.com",
            width=400 if not self.is_mobile else None,
        )
        
        self.status_text = ft.Text("Готов к работе", size=16)
        self.progress_bar = ft.ProgressBar(visible=False)
        self.result_container = ft.Column(scroll=ft.ScrollMode.AUTO)
        
        # Кнопки действий
        self.test_button = ft.ElevatedButton(
            "Тестировать домен",
            icon=ft.icons.PLAY_ARROW,
            on_click=self.test_domain,
        )
        
        self.auto_button = ft.ElevatedButton(
            "Авто-поиск стратегии",
            icon=ft.icons.AUTO_FIX_HIGH,
            on_click=self.auto_discover,
        )
        
        self.service_button = ft.ElevatedButton(
            "Запустить службу",
            icon=ft.icons.POWER_SETTINGS_NEW,
            on_click=self.toggle_service,
            disabled=not self.check_admin_rights(),
        )
        
        self.build_ui()
    
    def check_admin_rights(self) -> bool:
        """Проверка прав администратора"""
        if self.is_windows:
            import ctypes
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() == 1
            except:
                return False
        return True  # На Android проверяем root отдельно
    
    def build_ui(self):
        """Построение интерфейса"""
        # Заголовок
        header = ft.Container(
            content=ft.Column([
                ft.Text("🛡️ Recon DPI Bypass", size=32, weight=ft.FontWeight.BOLD),
                ft.Text("Обход блокировок DPI", size=16, color=ft.colors.GREY_400),
            ]),
            padding=ft.padding.only(bottom=20),
        )
        
        # Статус платформы
        platform_info = ft.Container(
            content=ft.Row([
                ft.Icon(ft.icons.COMPUTER if self.is_windows else ft.icons.PHONE_ANDROID),
                ft.Text(f"Платформа: {platform.system()}"),
                ft.Icon(ft.icons.ADMIN_PANEL_SETTINGS if self.check_admin_rights() else ft.icons.WARNING,
                       color=ft.colors.GREEN if self.check_admin_rights() else ft.colors.ORANGE),
            ]),
            bgcolor=ft.colors.SURFACE_VARIANT,
            padding=10,
            border_radius=10,
        )
        
        # Форма ввода
        input_section = ft.Container(
            content=ft.Column([
                self.domain_input,
                ft.Row([
                    self.test_button,
                    self.auto_button,
                ], wrap=True),
            ]),
            padding=ft.padding.symmetric(vertical=20),
        )
        
        # Управление службой
        service_section = ft.Container(
            content=ft.Column([
                ft.Divider(),
                ft.Text("Управление службой", size=20, weight=ft.FontWeight.BOLD),
                self.service_button,
                ft.Text(
                    "⚠️ Требуются права администратора" if not self.check_admin_rights() else "✅ Права администратора",
                    size=12,
                    color=ft.colors.ORANGE if not self.check_admin_rights() else ft.colors.GREEN,
                ),
            ]),
            padding=ft.padding.symmetric(vertical=20),
        )
        
        # Статус и результаты
        results_section = ft.Container(
            content=ft.Column([
                ft.Divider(),
                self.status_text,
                self.progress_bar,
                self.result_container,
            ]),
            padding=ft.padding.symmetric(vertical=20),
        )
        
        # Собираем все вместе
        main_column = ft.Column(
            [
                header,
                platform_info,
                input_section,
                service_section,
                results_section,
            ],
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )
        
        self.page.add(main_column)
    
    async def test_domain(self, e):
        """Тестирование домена"""
        domain = self.domain_input.value.strip()
        if not domain:
            self.show_error("Введите домен")
            return
        
        self.set_loading(True, f"Тестирование {domain}...")
        
        try:
            # Здесь вызываем вашу логику
            if CORE_AVAILABLE:
                # Пример интеграции с вашим кодом
                result = await self.run_test(domain)
                self.show_result(result)
            else:
                self.show_error("Модули core не загружены")
        except Exception as ex:
            self.show_error(f"Ошибка: {ex}")
        finally:
            self.set_loading(False)
    
    async def auto_discover(self, e):
        """Автоматический поиск стратегии"""
        domain = self.domain_input.value.strip()
        if not domain:
            self.show_error("Введите домен")
            return
        
        self.set_loading(True, f"Поиск стратегии для {domain}...")
        
        try:
            if CORE_AVAILABLE and self.adaptive_engine:
                # Интеграция с AdaptiveEngine
                strategy = await self.adaptive_engine.find_best_strategy(domain)
                self.show_strategy_result(strategy)
            else:
                self.show_error("AdaptiveEngine не инициализирован")
        except Exception as ex:
            self.show_error(f"Ошибка: {ex}")
        finally:
            self.set_loading(False)
    
    async def toggle_service(self, e):
        """Запуск/остановка службы"""
        # Здесь интеграция с вашим service mode
        self.show_info("Функция в разработке")
    
    async def run_test(self, domain: str) -> dict:
        """Запуск теста (интеграция с вашим кодом)"""
        # Заглушка - замените на реальную логику из cli.py
        await asyncio.sleep(2)
        return {
            "domain": domain,
            "status": "success",
            "strategy": "fake_multisplit",
            "time_ms": 250,
        }
    
    def show_result(self, result: dict):
        """Отображение результата"""
        self.result_container.controls.clear()
        
        result_card = ft.Container(
            content=ft.Column([
                ft.Text("✅ Результат теста", size=18, weight=ft.FontWeight.BOLD),
                ft.Text(f"Домен: {result['domain']}"),
                ft.Text(f"Статус: {result['status']}"),
                ft.Text(f"Стратегия: {result['strategy']}"),
                ft.Text(f"Время: {result['time_ms']}ms"),
            ]),
            bgcolor=ft.colors.GREEN_900,
            padding=15,
            border_radius=10,
        )
        
        self.result_container.controls.append(result_card)
        self.page.update()
    
    def show_strategy_result(self, strategy: dict):
        """Отображение найденной стратегии"""
        self.result_container.controls.clear()
        
        strategy_card = ft.Container(
            content=ft.Column([
                ft.Text("🎯 Найдена стратегия", size=18, weight=ft.FontWeight.BOLD),
                ft.Text(f"Тип: {strategy.get('type', 'unknown')}"),
                ft.Text(f"Параметры: {strategy.get('params', {})}"),
            ]),
            bgcolor=ft.colors.BLUE_900,
            padding=15,
            border_radius=10,
        )
        
        self.result_container.controls.append(strategy_card)
        self.page.update()
    
    def show_error(self, message: str):
        """Отображение ошибки"""
        self.status_text.value = f"❌ {message}"
        self.status_text.color = ft.colors.RED
        self.page.update()
    
    def show_info(self, message: str):
        """Отображение информации"""
        self.status_text.value = f"ℹ️ {message}"
        self.status_text.color = ft.colors.BLUE
        self.page.update()
    
    def set_loading(self, loading: bool, message: str = ""):
        """Установка состояния загрузки"""
        self.progress_bar.visible = loading
        self.test_button.disabled = loading
        self.auto_button.disabled = loading
        
        if loading:
            self.status_text.value = message
            self.status_text.color = ft.colors.BLUE
        else:
            self.status_text.value = "Готов к работе"
            self.status_text.color = ft.colors.WHITE
        
        self.page.update()


def main(page: ft.Page):
    """Точка входа приложения"""
    app = ReconDPIApp(page)


if __name__ == "__main__":
    # Запуск приложения
    # Для Windows: python gui_app.py
    # Для Android: flet build apk
    ft.app(target=main)
