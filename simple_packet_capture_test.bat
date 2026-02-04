@echo off
echo ================================================================================
echo Simple Packet Capture Test
echo ================================================================================
echo.
echo This will capture packets while you manually run curl in another window.
echo.
echo Step 1: This window will start capturing packets
echo Step 2: Open another CMD window and run:
echo         curl.exe -v https://www.google.com
echo Step 3: Come back here to see the captured packets
echo.
echo Press any key to start capture (will run for 30 seconds)...
pause >nul

python capture_inbound_packets_debug.py 0.0.0.0 443 30
