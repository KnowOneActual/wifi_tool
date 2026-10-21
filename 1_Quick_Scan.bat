@echo off
title Wi-Fi Live Scanner (2.4 / 5 / 6 GHz)
color 0A
echo =========================================================
echo         OPEN-SOURCE WI-FI LIVE SCANNER (WIN 11)
echo =========================================================
echo.
python "%~dp0survey_scanner.py" --scan
echo.
echo =========================================================
pause
