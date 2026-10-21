@echo off
title 802.11 RF Management Frame Capturer (TShark)
color 0E
echo =========================================================
echo      802.11 RF MANAGEMENT FRAME CAPTURE (TSHARK)
echo =========================================================
echo.
set /p DURATION="Enter capture duration in seconds (Default 30): "
if "%DURATION%"=="" set DURATION=30
set /p OUTNAME="Enter output filename (Default site_capture.pcapng): "
if "%OUTNAME%"=="" set OUTNAME=site_capture.pcapng
echo.
echo Starting capture on Wi-Fi interface for %DURATION% seconds...
python "%~dp0capture_packets.py" -i auto -d %DURATION% -o "%~dp0%OUTNAME%"
echo.
echo Capture complete! Saved to %OUTNAME%.
echo =========================================================
pause
