# run_dashboard.py
import time
import os
import sys
import logging
import json
import threading  # ИСПРАВЛЕНИЕ: Добавлен недостающий импорт

# --- Блок для настройки путей ---
if __name__ == "__main__" and __package__ is None:
    recon_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(recon_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    import recon

    __package__ = "recon"

from recon.core.signature_manager import SignatureManager
from recon.web.dashboard import ReconDashboard
from recon.recon_service import DPIBypassService

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
    service = DPIBypassService()
    service_thread = threading.Thread(target=service.run, daemon=True)
    service_thread.start()
    time.sleep(2)  # Даем время на инициализацию движка

    # This logic is flawed as the engine might not be created by the time this is called.
    # The dashboard should be robust to the engine not being available.
    if hasattr(service, 'bypass_engine'):
        bypass_engine_instance = service.bypass_engine
    else:
        bypass_engine_instance = None


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
        # Gracefully stop the service by setting the running flag to False
        service.running = False
        service_thread.join(timeout=5.0)


if __name__ == "__main__":
    main()
