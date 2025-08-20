# recon/setup_bypass.py
import os
import stat


class BypassSetup:
    """Автоматизирует создание скриптов для настройки обхода."""

    def setup_zapret_with_doh(self):
        """Создает shell-скрипт для запуска Zapret через DoH-мост."""
        script_content = """#!/bin/bash
#
# Скрипт для запуска Zapret с туннелированием через DoH-мост.
# ВНИМАНИЕ: Это экспериментальная функция!
#

# Запускаем DoH-мост в фоновом режиме
echo "Starting DoH Bridge in the background..."
python3 -c "from recon.tunnels.doh_zapret_bridge import DoHZapretBridge; DoHZapretBridge().start_bridge()" &
BRIDGE_PID=$!

# Даем мосту время на запуск
sleep 2

# Проверяем, запустился ли мост
if ! ps -p $BRIDGE_PID > /dev/null; then
   echo "Failed to start DoH Bridge."
   exit 1
fi

echo "DoH Bridge started with PID $BRIDGE_PID."
echo "Starting Zapret to use the bridge as a proxy..."

# Запускаем Zapret, указывая наш мост как прокси
# Укажите здесь путь к вашему исполняемому файлу Zapret
./zapret --dpi-desync=fake,disorder --dpi-desync-fooling=md5sig \\
         --proxy 127.0.0.1:8443

# Убиваем фоновый процесс моста после завершения работы Zapret
echo "Shutting down DoH Bridge..."
kill $BRIDGE_PID
"""

        script_path = "start_zapret_with_doh.sh"
        with open(script_path, "w") as f:
            f.write(script_content)

        # Делаем скрипт исполняемым
        os.chmod(
            script_path,
            stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH,
        )

        return script_path
