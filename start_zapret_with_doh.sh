#!/bin/bash
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
./zapret --dpi-desync=fake,disorder --dpi-desync-fooling=md5sig \
         --proxy 127.0.0.1:8443

# Убиваем фоновый процесс моста после завершения работы Zapret
echo "Shutting down DoH Bridge..."
kill $BRIDGE_PID
