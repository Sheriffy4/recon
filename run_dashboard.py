# run_dashboard.py
import time
import os
import sys
import logging
import threading  # ИСПРАВЛЕНИЕ: Добавлен недостающий импорт

# --- Блок для настройки путей ---
if __name__ == "__main__" and __package__ is None:
    recon_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(recon_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    __package__ = "recon"

from core.signature_manager import SignatureManager
from recon.web.dashboard import ReconDashboard
from recon.recon_service import ReconService

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
)


def main():
    """
    Запускает дашборд и, если возможно, службу обхода для live-статистики.
    """
    print("Инициализация менеджера сигнатур...")
    sig_manager = SignatureManager()

    # Пытаемся запустить службу, чтобы получить живую статистику
    bypass_engine_instance = None
    service = ReconService()
    service_thread = threading.Thread(target=service.start, daemon=True)
    service_thread.start()
    time.sleep(2)  # Даем время на инициализацию движка
    bypass_engine_instance = service.engine  # Получаем реальный экземпляр

    dashboard = ReconDashboard(
        signature_manager=sig_manager,
        bypass_engine=bypass_engine_instance,  # Передаем экземпляр
        port=8080,
    )

    if bypass_engine_instance:
        print("✅ Служба обхода запущена, live-статистика будет доступна.")
    else:
        print(
            "⚠️ Не удалось запустить службу (возможно, нет best_strategy.json). Live-статистика будет недоступна."
        )

    print("Инициализация дашборда...")
    dashboard = ReconDashboard(
        signature_manager=sig_manager,
        bypass_engine=bypass_engine_instance,  # Передаем экземпляр движка
        port=8080,
    )

    dashboard.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nЗавершение работы...")
        service.stop()


if __name__ == "__main__":
    main()
