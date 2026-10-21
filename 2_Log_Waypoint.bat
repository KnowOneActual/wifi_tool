@echo off
title Wi-Fi Waypoint Survey Logger
color 0B
echo =========================================================
echo         WI-FI SITE SURVEY WAYPOINT LOGGER
echo =========================================================
echo.
set /p WAYPOINT="Enter Room / Waypoint Name (e.g. Living Room, Office 101): "
if "%WAYPOINT%"=="" (
    echo [!] No waypoint entered. Exiting.
    pause
    exit /b
)
set /p SSID="Enter Target SSID to filter (Press Enter to log all networks): "
echo.
echo Scanning and recording at '%WAYPOINT%'...
if "%SSID%"=="" (
    python "%~dp0survey_scanner.py" --waypoint "%WAYPOINT%" --out "%~dp0survey_log.csv"
) else (
    python "%~dp0survey_scanner.py" --waypoint "%WAYPOINT%" --ssid "%SSID%" --out "%~dp0survey_log.csv"
)
echo.
echo Data saved to "%~dp0survey_log.csv".
echo =========================================================
pause
