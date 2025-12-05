@echo off
echo ================================================================================
echo Testing nnmclub.to with fake_mode: per_fragment
echo ================================================================================
echo.
echo Starting service with PCAP capture...
echo.

REM Start service and capture packets
python simple_service.py --pcap log_fake_mode_test.pcap --capture-max-seconds 30

echo.
echo ================================================================================
echo Service stopped. Analyzing PCAP...
echo ================================================================================
echo.

REM Analyze captured PCAP
python analyze_log_pcap.py log_fake_mode_test.pcap

echo.
echo ================================================================================
echo Test complete!
echo ================================================================================
echo.
echo Expected for nnmclub.to (fake_mode: per_fragment):
echo   - 6 fake packets (TTL=1, badseq)
echo   - 6 real packets (TTL=64)
echo   - Total: 12 packets
echo   - Disorder: reverse
echo.
pause
